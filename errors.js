
/**
 * Export errors codes.
 */

module.exports = {
  RoleNotFoundError: class RoleNotFoundError extends Error {
      constructor(roles) {
          super('Custom role not found');
          this.roles = roles;
      }
  }
}
