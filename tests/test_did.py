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


if __name__ == "__main__":
    unittest.main()
