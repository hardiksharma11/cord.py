import unittest
from unittest.mock import patch, MagicMock
import asyncio
import packages.sdk.src as Cord
from packages.utils.src.SDKErrors import Errors
from packages.utils.src.permissions import Permission

TEST_DID_URI = "did:cord:3vRsRQmgpuuyzkfMYwnAMuT9LKwxZMedbBGmAicrXk7EhsEr"
TEST_SPACE_URI = "space:cord:c348nKoDfByj4Eqo138ru8oT6nmY2BKPnGZqwpKGTyfgFRpFA"
TEST_AUTH_URI = "auth:cord:a3dm8W5ZM5mSJJRoWows6CCTEu5EvgB4WhmzaDZos54z3J2wK"
TEST_AUTHOR_ACCOUNT = MagicMock()
TEST_SIGN_CALLBACK = MagicMock()


class TestChainspaceFunctions(unittest.TestCase):
    module_path = "packages.sdk.src.Chainspace_Chain"

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.blake2_as_hex")
    @patch(f"{module_path}.hash_to_uri")
    @patch(f"{module_path}.to_chain")
    @patch(f"{module_path}.uri_to_identifier")
    def test_get_uri_for_space(
        self,
        mock_uri_to_identifier,
        mock_to_chain,
        mock_hash_to_uri,
        mock_blake2_as_hex,
        mock_config_service_get,
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api
        mock_api.encode_scale.return_value.get_remaining_bytes.return_value = (
            b"some_bytes"
        )
        mock_blake2_as_hex.return_value = "mock_digest"
        mock_hash_to_uri.side_effect = ["mockspaceuri", "mockauthuri"]
        mock_to_chain.return_value = "mock_chain_address"
        mock_uri_to_identifier.return_value = "mock_identifier"

        space_digest = "mock_space_digest"
        creator_uri = TEST_DID_URI

        result = asyncio.run(
            Cord.Chainspace_Chain.get_uri_for_space(space_digest, creator_uri)
        )

        self.assertEqual(result["uri"], "mockspaceuri")
        self.assertEqual(result["authorization_uri"], "mockauthuri")
        mock_blake2_as_hex.assert_called()
        mock_hash_to_uri.assert_called()
        mock_config_service_get.assert_called_with("api")
        mock_to_chain.assert_called_with(creator_uri)
        mock_uri_to_identifier.assert_called_with("mockspaceuri")

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.Did.authorize_tx")
    @patch(f"{module_path}.uri_to_identifier", return_value="mock_space_id")
    def test_sudo_approve_chain_space(
        self, mock_uri_to_identifier, mock_authorize_tx, mock_config_service_get
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api
        mock_authorize_tx.return_value = MagicMock()
        mock_api.compose_call.return_value = "mock_call"
        mock_api.create_signed_extrinsic = MagicMock(return_value="mock_extrinsic")
        mock_api.submit_extrinsic = MagicMock()

        authority = MagicMock()
        space_uri = "mock_space_uri"
        capacity = 100

        asyncio.run(
            Cord.Chainspace_Chain.sudo_approve_chain_space(
                authority, space_uri, capacity
            )
        )

        # Assertions
        mock_api.compose_call.assert_called()
        mock_api.create_signed_extrinsic.assert_called_with(
            call="mock_call", keypair=authority
        )
        mock_api.submit_extrinsic.assert_called_with(
            "mock_extrinsic", wait_for_inclusion=True
        )

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.Did.authorize_tx")
    def test_prepare_create_space_extrinsic(
        self, mock_authorize_tx, mock_config_service_get
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        chain_space = {"digest": "mock_digest"}
        creator_uri = TEST_DID_URI
        sign_callback = TEST_SIGN_CALLBACK
        author_account = TEST_AUTHOR_ACCOUNT

        # Mock authorize_tx to return a dummy extrinsic
        mock_authorize_tx.return_value = "mock_extrinsic"

        # Run the function
        result = asyncio.run(
            Cord.Chainspace_Chain.prepare_create_space_extrinsic(
                chain_space, creator_uri, sign_callback, author_account
            )
        )

        self.assertEqual(result, "mock_extrinsic")
        mock_api.compose_call.assert_called()
        mock_authorize_tx.assert_called()

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.prepare_create_space_extrinsic")
    def test_dispatch_to_chain(
        self, mock_prepare_create_space_extrinsic, mock_config_service_get
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        chain_space = {"uri": TEST_SPACE_URI, "authorization_uri": TEST_AUTH_URI}
        creator_uri = TEST_DID_URI
        author_account = TEST_AUTHOR_ACCOUNT
        sign_callback = TEST_SIGN_CALLBACK

        mock_prepare_create_space_extrinsic.return_value = "fake_extrinsic"
        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"
        mock_api.submit_extrinsic = MagicMock()
        # Run the function
        result = asyncio.run(
            Cord.Chainspace_Chain.dispatch_to_chain(
                chain_space, creator_uri, author_account, sign_callback
            )
        )

        self.assertEqual(
            result, {"uri": TEST_SPACE_URI, "authorization": TEST_AUTH_URI}
        )
        mock_prepare_create_space_extrinsic.assert_called_once_with(
            chain_space, creator_uri, sign_callback, author_account
        )
        mock_api.create_signed_extrinsic.assert_called_once_with(
            "fake_extrinsic", keypair=author_account
        )
        mock_api.submit_extrinsic.assert_called_once_with(
            "signed_extrinsic", wait_for_inclusion=True
        )

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.Did.authorize_tx")
    def test_dispatch_subspace_create_to_chain(
        self, mock_authorize_tx, mock_config_service_get
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        chain_space = {
            "digest": "mock_digest",
            "uri": TEST_SPACE_URI,
            "authorization_uri": TEST_AUTH_URI,
        }
        creator_uri = TEST_DID_URI
        author_account = TEST_AUTHOR_ACCOUNT
        count = 10
        parent = TEST_SPACE_URI
        sign_callback = TEST_SIGN_CALLBACK

        # Mock api.compose_call to return a fake transaction
        mock_api.compose_call.return_value = "fake_tx"

        # Mock Did.authorize_tx to return a fake extrinsic
        mock_authorize_tx.return_value = "authorized_extrinsic"

        # Mock api.create_signed_extrinsic to return a signed extrinsic
        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"

        # Run the function
        result = asyncio.run(
            Cord.Chainspace_Chain.dispatch_subspace_create_to_chain(
                chain_space, creator_uri, author_account, count, parent, sign_callback
            )
        )

        # Assert
        self.assertEqual(
            result, {"uri": TEST_SPACE_URI, "authorization": TEST_AUTH_URI}
        )

        # Assert that compose_call was called with the correct parameters
        mock_api.compose_call.assert_called_once_with(
            call_module="ChainSpace",
            call_function="subspace_create",
            call_params={
                "space_code": "mock_digest",
                "count": count,
                "space_id": TEST_SPACE_URI.replace("space:cord:", ""),
            },
        )

        # Assert that authorize_tx was called with the correct parameters
        mock_authorize_tx.assert_called_once_with(
            creator_uri, "fake_tx", sign_callback, author_account.ss58_address
        )

        # Assert that create_signed_extrinsic was called with the correct parameters
        mock_api.create_signed_extrinsic.assert_called_once_with(
            "authorized_extrinsic", keypair=author_account
        )

        # Assert that submit_extrinsic was called with the correct parameters
        mock_api.submit_extrinsic.assert_called_once_with(
            "signed_extrinsic", wait_for_inclusion=True
        )

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.Did.authorize_tx")
    def test_dispatch_update_tx_capacity_to_chain(
        self, mock_authorize_tx, mock_config_service_get
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        space = TEST_SPACE_URI
        creator_uri = TEST_DID_URI
        author_account = TEST_AUTHOR_ACCOUNT
        author_account.ss58_address = "mock_ss58_address"
        new_capacity = 200
        sign_callback = TEST_SIGN_CALLBACK

        # Mock api.compose_call to return a fake transaction
        mock_api.compose_call.return_value = "fake_tx"

        # Mock Did.authorize_tx to return a fake extrinsic
        mock_authorize_tx.return_value = "authorized_extrinsic"

        # Mock api.create_signed_extrinsic to return a signed extrinsic
        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"

        # Run the function
        result = asyncio.run(
            Cord.Chainspace_Chain.dispatch_update_tx_capacity_to_chain(
                space, creator_uri, author_account, new_capacity, sign_callback
            )
        )

        # Assert
        self.assertEqual(result, {"uri": space})

        # Verify that compose_call was called correctly
        mock_api.compose_call.assert_called_once_with(
            call_module="ChainSpace",
            call_function="update_transaction_capacity_sub",
            call_params={
                "space_id": space.replace("space:cord:", ""),
                "new_txn_capacity": new_capacity,
            },
        )

        # Verify that authorize_tx was called with the correct parameters
        mock_authorize_tx.assert_called_once_with(
            creator_uri, "fake_tx", sign_callback, "mock_ss58_address"
        )

        # Verify that create_signed_extrinsic was called correctly
        mock_api.create_signed_extrinsic.assert_called_once_with(
            "authorized_extrinsic", keypair=author_account
        )

        # Verify that submit_extrinsic was called correctly
        mock_api.submit_extrinsic.assert_called_once_with(
            "signed_extrinsic", wait_for_inclusion=True
        )

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.blake2_as_hex")
    @patch(f"{module_path}.hash_to_uri")
    @patch(f"{module_path}.Did.to_chain")
    @patch(f"{module_path}.uri_to_identifier")
    def test_get_uri_for_authorization(
        self,
        mock_uri_to_identifier,
        mock_to_chain,
        mock_hash_to_uri,
        mock_blake2_as_hex,
        mock_config_service_get,
    ):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api
        mock_api.encode_scale.return_value.get_remaining_bytes.return_value = (
            b"some_bytes"
        )
        mock_blake2_as_hex.return_value = "mock_auth_digest"
        mock_hash_to_uri.return_value = "mock_auth_uri"
        mock_to_chain.return_value = "mock_chain_address"
        mock_uri_to_identifier.return_value = "mock_identifier"

        space_uri = TEST_SPACE_URI
        delegate_uri = TEST_DID_URI
        creator_uri = TEST_DID_URI

        result = asyncio.run(
            Cord.Chainspace_Chain.get_uri_for_authorization(
                space_uri, delegate_uri, creator_uri
            )
        )

        self.assertEqual(result, "mock_auth_uri")
        mock_blake2_as_hex.assert_called()
        mock_hash_to_uri.assert_called()
        mock_config_service_get.assert_called_with("api")
        mock_to_chain.assert_called_with(delegate_uri)
        mock_uri_to_identifier.assert_called_with(space_uri)

    @patch(f"{module_path}.ConfigService.get")
    def test_dispatch_delegate_authorization_tx(self, mock_config_service_get):
        mock_api = MagicMock()
        mock_config_service_get.return_value = mock_api

        # Test cases for each permission type
        test_cases = [
            (Permission.ASSERT, "add_delegate"),
            (Permission.DELEGATE, "add_delegator"),
            (Permission.ADMIN, "add_admin_delegate"),
        ]

        space_id = "mock_space_id"
        delegate_id = "mock_delegate_id"
        auth_id = "mock_auth_id"

        for permission, expected_function in test_cases:
            with self.subTest(permission=permission):
                tx = asyncio.run(
                    Cord.Chainspace_Chain.dispatch_delegate_authorization_tx(
                        permission, space_id, delegate_id, auth_id
                    )
                )
                mock_api.compose_call.assert_called_with(
                    call_module="ChainSpace",
                    call_function=expected_function,
                    call_params={
                        "space_id": space_id,
                        "delegate": delegate_id,
                        "authorization": auth_id,
                    },
                )
                self.assertEqual(tx, mock_api.compose_call.return_value)

    @patch(f"{module_path}.ConfigService.get")
    def test_dispatch_delegate_authorization_tx_invalid_permission(
        self, mock_config_service_get
    ):
        with self.assertRaises(Errors.CordDispatchError):
            asyncio.run(
                Cord.Chainspace_Chain.dispatch_delegate_authorization_tx(
                    "INVALID_PERMISSION",
                    "mock_space_id",
                    "mock_delegate_id",
                    "mock_auth_id",
                )
            )


if __name__ == "__main__":
    unittest.main()