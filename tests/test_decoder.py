from __future__ import annotations

import unittest

from evm_call_explainer import CalldataDecoder, Confidence
from evm_call_explainer.abi import AbiDecodingError
from evm_call_explainer.abi_types import decode_abi_parameters
from evm_call_explainer.keccak import function_selector
from evm_call_explainer.models import ContractInfo, DecodedCall
from evm_call_explainer.preflight import CheckStatus, PreflightRunner
from evm_call_explainer.render import EnglishRenderer
from evm_call_explainer.rpc import RpcClient, RpcEvidenceResolver
from evm_call_explainer.reverts import decode_revert_data
from evm_call_explainer.signature_lookup import (
    SignatureCandidate,
    SignatureEvidenceResolver,
    parse_function_signature,
)
from evm_call_explainer.verified_abi import VerifiedContract, apply_verified_abi


MULTICALL = "0xca11bde05977b3631167028862be2a173976ca11"
ORACLE = "0x61fc7230bf80f0c83622f951d2f97140097a49bd"
ASSET_A = "0x37fc9e86cf57ba8035696052ec1a5f767ad7c096"
ASSET_B = "0x101f3ae9414bd27d82cc03eb8d5a827249baf60c"
CELO = "0x471ece3750da237f93b8e339c536989b8978a438"
TOKEN = "0xf50fff154e63e510e494929e9eab1e9c5047429e"
WALLET = "0xf13918dce6f2ae689548478cb83e4cad836adb7a"


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def address_word(address: str) -> bytes:
    return bytes(12) + bytes.fromhex(address[2:])


def address_call(selector: str, address: str) -> bytes:
    return bytes.fromhex(selector[2:]) + address_word(address)


def tuple_encoding(target: str, allow_failure: bool, call_data: bytes) -> bytes:
    padding = bytes((-len(call_data)) % 32)
    return address_word(target) + word(int(allow_failure)) + word(96) + word(len(call_data)) + call_data + padding


def aggregate3(calls: list[tuple[str, bool, bytes]]) -> str:
    tuples = [tuple_encoding(*call) for call in calls]
    offset = 32 * len(tuples)
    heads = []
    for encoded in tuples:
        heads.append(word(offset))
        offset += len(encoded)
    array = word(len(tuples)) + b"".join(heads) + b"".join(tuples)
    return "0x82ad56cb" + (word(32) + array).hex()


def dynamic_bytes(value: bytes) -> bytes:
    return word(len(value)) + value + bytes((-len(value)) % 32)


class DecoderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = aggregate3(
            [
                (ORACLE, True, address_call("0x37cef791", ASSET_A)),
                (ORACLE, True, address_call("0x37cef791", ASSET_B)),
                (ORACLE, True, address_call("0x37cef791", CELO)),
                (TOKEN, True, address_call("0x70a08231", WALLET)),
                (ASSET_A, True, address_call("0x70a08231", WALLET)),
                (ASSET_B, True, address_call("0x70a08231", WALLET)),
                (CELO, True, address_call("0x70a08231", WALLET)),
            ]
        )

    def test_decodes_seven_nested_calls(self) -> None:
        report = CalldataDecoder().decode(MULTICALL, self.data)

        self.assertEqual(report.root.signature, "aggregate3((address,bool,bytes)[])")
        self.assertEqual(report.root.confidence, Confidence.CONFIRMED)
        self.assertEqual(len(report.root.children), 7)
        self.assertEqual(
            [call.signature for call in report.root.children],
            ["getRate(address)"] * 3 + ["balanceOf(address)"] * 4,
        )
        self.assertEqual(report.root.children[0].arguments, [ASSET_A])
        self.assertEqual(report.root.children[-1].arguments, [WALLET])
        self.assertTrue(all(call.allow_failure for call in report.root.children))

    def test_rejects_short_calldata(self) -> None:
        with self.assertRaises(AbiDecodingError):
            CalldataDecoder().decode(MULTICALL, "0x1234")

    def test_unknown_selector_is_preserved(self) -> None:
        report = CalldataDecoder().decode(ORACLE, "0xdeadbeef")
        self.assertIsNone(report.root.signature)
        self.assertEqual(report.root.selector, "0xdeadbeef")
        self.assertEqual(report.root.confidence, Confidence.UNKNOWN)

    def test_plain_english_summary(self) -> None:
        report = CalldataDecoder().decode(MULTICALL, self.data)
        rendered = EnglishRenderer().render(report)
        self.assertIn("perform 7 contract calls", rendered)
        self.assertIn("for the rate of", rendered)
        self.assertIn("balance owned by", rendered)
        self.assertIn("No RPC simulation ran", rendered)

    def test_ethereum_keccak_selectors(self) -> None:
        self.assertEqual(function_selector("balanceOf(address)"), "0x70a08231")
        self.assertEqual(function_selector("aggregate3((address,bool,bytes)[])"), "0x82ad56cb")

    def test_verified_abi_confirms_a_signature(self) -> None:
        raw = address_call("0x37cef791", ASSET_A)
        call = DecodedCall(ORACLE, "0x" + raw.hex(), "0x37cef791")
        contract = VerifiedContract(
            ORACLE,
            [
                {
                    "type": "function",
                    "name": "getRate",
                    "stateMutability": "view",
                    "inputs": [{"name": "asset", "type": "address"}],
                    "outputs": [{"name": "rate", "type": "uint256"}],
                }
            ],
            "exact_match",
            "test fixture",
        )
        self.assertTrue(apply_verified_abi(call, contract))
        self.assertEqual(call.signature, "getRate(address)")
        self.assertEqual(call.arguments, [ASSET_A])
        self.assertTrue(call.arguments_decoded)
        self.assertEqual(call.confidence, Confidence.CONFIRMED)

    def test_local_preflight_passes_with_network_warnings(self) -> None:
        report = PreflightRunner(config={}).run()
        self.assertTrue(report.passed)
        self.assertFalse(any(check.status == CheckStatus.FAIL for check in report.checks))
        self.assertTrue(any(check.status == CheckStatus.WARN for check in report.checks))

    def test_payload_size_limit_is_enforced(self) -> None:
        with self.assertRaises(AbiDecodingError):
            CalldataDecoder(max_payload_bytes=4).decode(ORACLE, "0xdeadbeef00")

    def test_invalid_block_tag_is_rejected(self) -> None:
        with self.assertRaises(AbiDecodingError):
            CalldataDecoder().decode(ORACLE, "0xdeadbeef", "yesterday")

    def test_rpc_url_requires_http_or_https(self) -> None:
        with self.assertRaises(ValueError):
            RpcClient("file:///private/rpc")

    def test_general_decoder_handles_dynamic_and_nested_inputs(self) -> None:
        parameters = [
            {"name": "memo", "type": "string"},
            {"name": "amounts", "type": "uint256[]"},
            {
                "name": "metadata",
                "type": "tuple",
                "components": [
                    {"name": "account", "type": "address"},
                    {"name": "enabled", "type": "bool"},
                ],
            },
        ]
        string_body = dynamic_bytes(b"hello")
        array_body = word(3) + word(10) + word(20) + word(30)
        head_size = 4 * 32
        encoded = (
            word(head_size)
            + word(head_size + len(string_body))
            + address_word(ASSET_A)
            + word(1)
            + string_body
            + array_body
        )

        decoded = decode_abi_parameters(encoded, parameters)

        self.assertEqual(decoded[0], "hello")
        self.assertEqual(decoded[1], [10, 20, 30])
        self.assertEqual(decoded[2], {"account": ASSET_A, "enabled": True})

    def test_general_decoder_handles_dynamic_tuple_array(self) -> None:
        parameters = [
            {
                "name": "items",
                "type": "tuple[]",
                "components": [
                    {"name": "account", "type": "address"},
                    {"name": "note", "type": "string"},
                ],
            }
        ]
        first_note = dynamic_bytes(b"first")
        second_note = dynamic_bytes(b"second")
        first_tuple = address_word(ASSET_A) + word(64) + first_note
        second_tuple = address_word(ASSET_B) + word(64) + second_note
        array_head_size = 2 * 32
        array_body = (
            word(2)
            + word(array_head_size)
            + word(array_head_size + len(first_tuple))
            + first_tuple
            + second_tuple
        )
        encoded = word(32) + array_body

        decoded = decode_abi_parameters(encoded, parameters)

        self.assertEqual(
            decoded[0],
            [
                {"account": ASSET_A, "note": "first"},
                {"account": ASSET_B, "note": "second"},
            ],
        )

    def test_standard_revert_reason_is_decoded(self) -> None:
        error_data = "0x08c379a0" + (word(32) + dynamic_bytes(b"not allowed")).hex()
        panic_data = "0x4e487b71" + word(0x11).hex()

        self.assertEqual(decode_revert_data(error_data), "Error('not allowed')")
        self.assertIn("arithmetic overflow", decode_revert_data(panic_data) or "")

    def test_verified_abi_decodes_dynamic_function_arguments(self) -> None:
        inputs = [
            {"name": "message", "type": "string"},
            {"name": "amounts", "type": "uint256[]"},
        ]
        signature = "setMessage(string,uint256[])"
        string_body = dynamic_bytes(b"hello")
        array_body = word(2) + word(7) + word(9)
        encoded_arguments = word(64) + word(64 + len(string_body)) + string_body + array_body
        selector = function_selector(signature)
        call = DecodedCall(ORACLE, selector + encoded_arguments.hex(), selector)
        contract = VerifiedContract(
            ORACLE,
            [
                {
                    "type": "function",
                    "name": "setMessage",
                    "stateMutability": "nonpayable",
                    "inputs": inputs,
                    "outputs": [],
                }
            ],
            "exact_match",
            "test fixture",
        )

        self.assertTrue(apply_verified_abi(call, contract))
        self.assertEqual(call.arguments, ["hello", [7, 9]])
        self.assertTrue(call.arguments_decoded)
        self.assertEqual(call.confidence, Confidence.CONFIRMED)

    def test_generic_dynamic_return_value_is_decoded(self) -> None:
        call = DecodedCall(
            ORACLE,
            "0x95d89b41",
            "0x95d89b41",
            signature="symbol()",
            output_parameters=[{"name": "", "type": "string"}],
        )
        result = word(32) + dynamic_bytes(b"TOKEN")

        RpcEvidenceResolver._decode_return_value(call, result)

        self.assertTrue(call.return_decoded)
        self.assertEqual(call.return_value, "TOKEN")

    def test_malformed_return_value_falls_back_to_raw_data(self) -> None:
        call = DecodedCall(
            ORACLE,
            "0x95d89b41",
            "0x95d89b41",
            signature="symbol()",
            output_parameters=[{"name": "", "type": "string"}],
        )

        RpcEvidenceResolver._decode_return_value(call, b"")

        self.assertFalse(call.return_decoded)
        self.assertIsNone(call.return_value)

    def test_unaligned_dynamic_offset_is_rejected(self) -> None:
        with self.assertRaises(AbiDecodingError):
            decode_abi_parameters(word(1) + bytes(64), [{"name": "value", "type": "string"}])

    def test_verified_custom_error_is_decoded(self) -> None:
        definition = {
            "type": "error",
            "name": "Unauthorized",
            "inputs": [
                {"name": "account", "type": "address"},
                {"name": "required", "type": "uint256"},
            ],
        }
        signature = "Unauthorized(address,uint256)"
        data = function_selector(signature) + (address_word(WALLET) + word(50)).hex()

        self.assertEqual(
            decode_revert_data(data, [definition]),
            f"Unauthorized('{WALLET}', 50)",
        )

    def test_dynamic_bytes_boundary_lengths(self) -> None:
        parameter = [{"name": "payload", "type": "bytes"}]
        for length in (0, 1, 31, 32, 33, 255):
            with self.subTest(length=length):
                value = bytes(index % 256 for index in range(length))
                encoded = word(32) + dynamic_bytes(value)
                self.assertEqual(decode_abi_parameters(encoded, parameter), ["0x" + value.hex()])

    def test_signature_text_parser_handles_nested_tuples(self) -> None:
        name, inputs = parse_function_signature(
            "route((address,uint256)[],bytes32)"
        )
        self.assertEqual(name, "route")
        self.assertEqual(inputs[0]["type"], "tuple[]")
        self.assertEqual([item["type"] for item in inputs[0]["components"]], ["address", "uint256"])
        self.assertEqual(inputs[1]["type"], "bytes32")

    def test_signature_resolver_decodes_unknown_call(self) -> None:
        signature = "messageFor(address,string)"
        selector = function_selector(signature)
        text_body = dynamic_bytes(b"hello")
        arguments = address_word(WALLET) + word(64) + text_body
        report = CalldataDecoder().decode(ORACLE, selector + arguments.hex())

        class FakeLookup:
            def lookup(self, selectors):
                self.seen = selectors
                return {
                    selector: [
                        SignatureCandidate(
                            signature,
                            [
                                {"name": "", "type": "address"},
                                {"name": "", "type": "string"},
                            ],
                            True,
                        )
                    ]
                }

        lookup = FakeLookup()
        SignatureEvidenceResolver(lookup).enrich(report)

        self.assertEqual(lookup.seen, [selector])
        self.assertEqual(report.root.signature, signature)
        self.assertEqual(report.root.arguments, [WALLET, "hello"])
        self.assertEqual(report.root.confidence, Confidence.LIKELY)

    def test_missing_called_contract_produces_wrong_chain_warning(self) -> None:
        raw = address_call("0x70a08231", WALLET)
        report = CalldataDecoder().decode(TOKEN, "0x" + raw.hex())
        report.contracts[TOKEN] = ContractInfo(TOKEN, code_present=False)

        RpcEvidenceResolver._warn_for_missing_call_targets([report.root], report)

        self.assertTrue(any("verify that the RPC" in warning for warning in report.warnings))

    def test_offline_report_names_only_local_evidence(self) -> None:
        report = CalldataDecoder().decode(TOKEN, "0x" + address_call("0x70a08231", WALLET).hex())
        rendered = EnglishRenderer().render(report)

        self.assertIn("Evidence sources: local ABI analysis", rendered)
        self.assertNotIn("Sourcify 4byte signatures", rendered)


if __name__ == "__main__":
    unittest.main()
