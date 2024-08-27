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


if __name__ == "__main__":
    unittest.main()
