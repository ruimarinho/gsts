
/**
 * Role represents a combination of a AWS
 * Role ARN and Principal ARN.
 */

module.exports = class Role {
  constructor(name, roleArn, principalArn, sessionDuration) {
    if (!name) {
      throw new Error('Role name is required');
    }

    if (!roleArn) {
      throw new Error('Role ARN is required');
    }

    if (!principalArn) {
      throw new Error('Principal ARN is required');
    }

    this.name = name;
    this.roleArn = roleArn;
    this.principalArn = principalArn;
    this.sessionDuration = sessionDuration;
  }
}
