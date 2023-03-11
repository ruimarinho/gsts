
/**
 * RoleNotFoundError class.
 */

export class RoleNotFoundError extends Error {
    constructor(roles) {
        super('Custom role not found');
        this.roles = roles;
    }
}

/**
 * ProfileNotFoundError class.
 */

export class ProfileNotFoundError extends Error {
    constructor(profile) {
        super(`Profile "${profile}" not found in credentials file`);
        this.profile = profile;
    }
}

/**
 * RoleMismatchError class.
 */

export class RoleMismatchError extends Error {
    constructor(receivedRole, expectedRole) {
        super(`Received role ${receivedRole} but expected ${expectedRole}`);

        this.receivedRole = receivedRole;
        this.expectedRole = expectedRole;
    }
}
