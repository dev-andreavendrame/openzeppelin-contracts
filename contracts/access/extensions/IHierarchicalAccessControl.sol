// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/HierarchicalAccessControl.sol)

pragma solidity ^0.8.19;

/**
 * @dev Extension of {AccessControl} that allows to define a tree type hierarchy between
 * the granted roles.
 * The roles hierarchy has an immutable root that is represented by the `DEFAULT_ADMIN_ROLE`
 * and this role is able to revoke and grant any other role.
 *
 * This extension allows to define different levels of authority and relationships between
 * different roles aiming to limit the enable the access to specific function to specific
 * roles and roles that has a higher autority in the hierarchy.
 *
 * To achieve this mechanism has been introduced the `atLeast(role)` modifier where the
 * variable `role` has the same meaning of the {AccessControl} standard.
 *
 * --- How it works ---
 *
 * Imagining that a smart contract implements this extension and has different functions
 * and each function should be executed from a specific role defined into a hierarchy.
 * Keeping things simple we define a 3 level hierarchy where the higher authority
 * is the administrator with granted the `DEFAULT_ADMIN_ROLE` role.
 * The middle level is represented by the manager which has been granted the `MANAGER_ROLE`
 * and finally we have the user with no roles granted.
 *
 * The hierarchy defined above can be represented as the following schema:
 *
 * `DEFAULT_ADMIN_ROLE` --> `MANAGER_ROLE` --> `NO_ROLE`
 *
 * where the relationship 'ROLE_A --> ROLE_B' arrow means that 'ROLE_A' can
 * act as the 'ROLE_B', but not the opposite.
 *
 * Important: following the example above the `NO_ROLE` tole cannot acts as an
 * `DEFAULT_ADMIN_ROLE` since a check should be done before granting the `NO_ROLE`
 * role to anybody in order to prevent loops in the hierarchy.
 *
 * Based on the previous description a contract that inherit from a {HierarchicalAccessControl}
 * is able to use the modifier `atLeast(role)` as defined below letting both
 * `DEFAULT_ADMIN_ROLE` role and `MANAGER_ROLE` role to execute the
 * `foo()` function.
 *
 * ```solidity
 * bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
 *
 * function foo() public atLeast(MANAGER_ROLE) {
 *     ...
 * }
 * ```
 * As an extension of the {AccessControl} standard, the {HierarchicalAccessControl}
 * should be able to change the admin of a specified role.
 * To change the admin of a specific role means that all the sub-hierarchy that
 * relies on this role is moved as well.
 * The admin of a specific role is the next role in the hierarchy level (referring to
 * the example above the `MANAGER_ROLE`'s role admin is the `DEFAULT_ADMIN_ROLE` role).
 * The admin role of the `DEFAULT_ADMIN_ROLE` is the `DEFAULT_ADMIN_ROLE` itself.
 *
 * When granting a new role for the first time the parent role in the hierarchy
 * must be passed as an additional parameter, otherwise the admin for the this new
 * role will automatically set to be the `DEFAULT_ADMIN_ROLE`.
 * This will lead to defined a complete hierarchy with no holes.
 *
 * Revoking a role can be done with no concerning untile there is only one account that
 * has granted this role. When the last account that has this role loses it the
 * child (or children) roles in the hierarchy are attached to the parent role
 * of the current one automatically.
 *
 * --- Hierarchy inspection ---
 *
 * The contract must maintain a unique roles set that can be used to recreate
 * the hierarchy and understand which are the roles contained at a specific point
 * in time.
 * The functions for inspecting the hierarchy need to allow the user to
 * retrieve the set of roles that the hierarchy is composed of and
 * to ask if a give `ROLE_A` is able to act as another `ROLE_B`, meaning
 * that the `ROLE_B` is in a lower position in the hierarchy.
 *
 * * Note: The address(0) cannot be granted roles in order to prevent unexpected behaviours.
 *
 */

interface IHierarchicalAccessControl {
    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     * - the caller must not have another role already assigned, otherwise
     *   revers with "`account` has already a `assignedRole` assigned" where
     *  `assignedRole` is the current ``account``'s role.
     * - the caller must have ``role``'s admin role or `role` must be assigned
     *   for the first time .
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Returns a list of all the roles included in the hierarchy.
     *
     * Note: initially, before granting any role, the result of this
     * function is the following one element array [`DEFAULT_ADMIN_ROLE`].
     */
    function getHierarchyRoles() external returns (bytes32[] memory);

    /**
     * @dev returns `true` if going up in the hierarchy starting from
     * `targetRole` at some point the the roles owned by `account` is
     * reached, `false` otherwise.
     *
     * Note: if `account` has been granted the `DEFAULT_ADMIN_ROLE` the
     * result is always `true`.
     */
    function canBehaveLike(address account, bytes32 targetRole) external view returns (bool);

    /**
     * @dev returns the role granted to `account`
     *
     * Requirements:
     * - `account` must have granted a role otherwise the function
     *   reverts with "`account` has no role granted"
     */
    function getRole(address account) external view returns (bytes32);

    /**
     * @dev returns `true` if `account` has been granted a role,
     * `false` otherwise
     */
    function hasARole(address account) external view returns (bool);
}
