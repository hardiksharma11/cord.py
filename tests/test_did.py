import unittest
from unittest.mock import patch, MagicMock
import asyncio
import packages.sdk.src as Cord

class TestCordSDKFunctions(unittest.TestCase):

    def test_to_chain(self):
        did_uri = "did:cord:3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr"
        self.assertEqual(Cord.Did.to_chain(did_uri), "3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr")

    def test_from_chain(self):
        encoded = "3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr"
        self.assertEqual(Cord.Did.from_chain(encoded), "did:cord:3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr")

    def test_resource_id_to_chain(self):
        resource_id = "#my-service"
        self.assertEqual(Cord.Did.resource_id_to_chain(resource_id), "my-service")

    def test_is_uri_valid(self):
        valid_uri = "https://www.example.com"
        invalid_uri = "ht@tp://example"
        self.assertTrue(Cord.Did.is_uri(valid_uri))
        self.assertFalse(Cord.Did.is_uri(invalid_uri))

    @patch("packages.utils.src.SDKErrors.DidError", side_effect=Exception)
    def test_validate_service(self, mock_error):
        valid_service = {
            "id": "#my-service",
            "service_endpoint": ["https://www.example.com"]
        }

        invalid_service = {
            "id": "did:cord:12345#my-service",
            "service_endpoint": ["not-a-url"]
        }

        # Should not raise an exception
        Cord.Did.validate_service(valid_service)

        # Should raise an exception
        with self.assertRaises(Exception):
            Cord.Did.validate_service(invalid_service)

    def test_service_to_chain(self):
        service = {
            "id": "#my-service",
            "type": ["some-type"],
            "service_endpoint": ["https://www.example.com"]
        }
        expected_result = {
            "id": "my-service",
            "service_types": [["some-type"]],
            "urls": [["https://www.example.com"]]
        }
        self.assertEqual(Cord.Did.service_to_chain(service), expected_result)

    def test_public_key_to_chain(self):
        key = {
            "crypto_type": "Ed25519",
            "public_key": bytes.fromhex("deadbeef")
        }
        expected_result = [{"Ed25519": "0xdeadbeef"}]
        self.assertEqual(Cord.Did.public_key_to_chain(key), expected_result)

    def test_public_key_to_chain_for_keypair(self):
        keypair = MagicMock()
        keypair.crypto_type = 0  # Ed25519
        keypair.public_key = bytes.fromhex("deadbeef")
        expected_result = {"Ed25519": "0xdeadbeef"}
        self.assertEqual(Cord.Did.public_key_to_chain_for_keypair(keypair), expected_result)

    def test_increase_nonce(self):
        MAX_NONCE_VALUE = int(pow(2, 64) - 1)
        self.assertEqual(Cord.Did.increase_nonce(5), 6)
        self.assertEqual(Cord.Did.increase_nonce(MAX_NONCE_VALUE), 1)

    @patch("packages.sdk.src.ConfigService.get")
    def test_get_next_nonce(self, mock_get):
        mock_get.return_value.query.return_value.value = {"last_tx_counter": "5"}
        did = "did:cord:3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr"
        result = Cord.Did.get_next_nonce(did)
        self.assertEqual(result, 6)

    @patch("packages.did.src.Did_chain.get_key_relationship_for_method", return_value="authentication")
    @patch("packages.did.src.Did_chain.generate_did_authenticated_tx", return_value="mocked_tx")
    @patch("packages.did.src.Did_chain.get_next_nonce", return_value=1)
    def test_authorize_tx(self, mock_relationship, mock_tx, mock_nonce):
        did = "did:cord:12345"
        extrinsic = MagicMock()
        sign = MagicMock()
        submitter_account = MagicMock()

        result = asyncio.run(Cord.Did.authorize_tx(did, extrinsic, sign, submitter_account))
        self.assertEqual(result, "mocked_tx")

    def test_get_key_relationship_for_tx(self):
        extrinsic = MagicMock()
        extrinsic.method = MagicMock()
        with patch("packages.sdk.src.Did.get_key_relationship_for_method", return_value="authentication"):
            self.assertEqual(Cord.Did.get_key_relationship_for_tx(extrinsic), "authentication")

    def test_get_key_relationship_for_method(self):
        call = MagicMock()
        call.call_module = {"name": "Did"}
        call.call_function = {"name": "create"}
        self.assertIsNone(Cord.Did.get_key_relationship_for_method(call))

    @patch('packages.sdk.src.Did.generate_mnemonic')
    @patch('packages.sdk.src.Did.generate_keypairs')
    @patch('packages.sdk.src.Did.get_store_tx')
    @patch('packages.sdk.src.ConfigService.get')
    def test_create_did(self, mock_config_service_get, mock_get_store_tx, mock_generate_keypairs, mock_generate_mnemonic):
        # Mock the return values of the functions and methods
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        mnemonic = "use stereo ostrich special broccoli hurdle share subway jewel truck almost noodle loud goat more enhance brisk hope attend girl city catch mistake differ"
        mock_generate_mnemonic.return_value = mnemonic
        mock_keypairs = {
            "authentication": MagicMock(),
            "key_agreement": MagicMock(),
            "assertion_method": MagicMock(),
            "capability_delegation": MagicMock()
        }
        mock_generate_keypairs.return_value = mock_keypairs
        
        mock_get_store_tx.return_value = "mocked_tx"

        mock_api.create_signed_extrinsic = MagicMock()
        mock_api.submit_extrinsic = MagicMock()
        mock_api.runtime_call = MagicMock(return_value="mocked_encoded_did")

        with patch('packages.sdk.src.Did.get_did_uri_from_key', return_value="did:cord:3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr") as mock_get_did_uri_from_key, \
             patch('packages.sdk.src.Did.linked_info_from_chain', return_value={"document": "mocked_document"}) as mock_linked_info_from_chain:

            submitter_account = MagicMock()
            submitter_account.ss58_address = "mocked_address"

            # Call the function
            result = asyncio.run(Cord.Did.create_did(submitter_account))

            # Assertions
            mock_generate_mnemonic.assert_called_once_with(24)
            mock_generate_keypairs.assert_called_once_with(mnemonic, "sr25519")
            mock_get_store_tx.assert_called_once()
            mock_api.create_signed_extrinsic.assert_called_once_with("mocked_tx", submitter_account)
            mock_api.submit_extrinsic.assert_called_once()
            mock_get_did_uri_from_key.assert_called_once()
            mock_api.runtime_call.assert_called_once_with("DidApi", "query", ["3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr"])
            mock_linked_info_from_chain.assert_called_once_with("mocked_encoded_did")

            self.assertEqual(result["mnemonic"], mnemonic)
            self.assertEqual(result["document"], "mocked_document")

if __name__ == "__main__":
    unittest.main()
