
/**
 * RoleNotFoundError class.
 */

export class RoleNotFoundError extends Error {
    constructor(roles) {
        super('Custom role not found');
        this.roles = roles;
    }
}
