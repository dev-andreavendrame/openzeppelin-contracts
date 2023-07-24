// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (access/HierarchyAccessControl.sol)

pragma solidity ^0.8.19;

import {AccessControl} from "../AccessControl.sol";
import {IHierarchicalAccessControl} from "./IHierarchicalAccessControl.sol";

/**
 * @dev Extension of {AccessControl} that allows enumerating the members of each role.
 */
abstract contract HierarchicalAccessControl is AccessControl, IHierarchicalAccessControl {
    mapping(bytes32 => bytes32) private _parentRoles;
    mapping(address => bytes32) private _accountRoles;
    mapping(address => bool) private _hasRolesAssigned;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IHierarchicalAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Modifier that checks that an account has at least the specified role.
     * Reverts with a standardized message including the required role.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^IHierarchicalAccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     */
    modifier hasAtLeastRole(bytes32 role) {
        require(_checkAtLeastRole(msg.sender, role), abi.encodePacked(ms););
        _;
    }

    /**
     * @dev returns `true` if `account` has a role that is able
     * to act as at least `role`, `false` otherwise.
     *
     * Note: if `account` has a higher role level related to
     * `role` the hierarchy is explored starting from the `role`
     * up to the root searching if one of the encountered roles
     * is the target one.
     */
    function _checkAtLeastRole(address account, bytes32 role) public view returs(bool) {
        bytes32 accountRole = _accountRoles[account];

        // Check if `account` has granted `role`
        if (accountRole == role) {
            return true;
        }

        /**
         * Check if `account` has a higher role in the
         * hierarchy (bottom-up research)
         */
        bytes32[] memory hierarchyBranch;
        bytes32 currentRole = accountRole;
        while (currentRole != DEFAULT_ADMIN_ROLE) {
            bytes32 currentAdmin = getRoleAdmin;
            hierarchyBranch.push(currentAdmin);
        }
        for (uint256 i = 0; i < hierarchyBranch.length; i++) {
            if (accountRole == hierarchyBranch[i]) {
                return true;
            }
        }

        // `account` is not able to act as `role`
        return false;
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _parentRoles[role];
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(
        bytes32 role,
        address account
    ) public virtual override(AccessControl, IHierarchicalAccessControl) onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }
}
