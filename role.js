
/**
 * Role represents a combination of a AWS
 * Role ARN and Principal ARN.
 */

module.exports = class Role {
  constructor(roleArn, principalArn) {
    if (!roleArn) {
      throw new Error('Role ARN is required');
    }

    if (!principalArn) {
      throw new Error('Principal ARN is required');
    }

    this.roleArn = roleArn;
    this.principalArn = principalArn;
  }
}
