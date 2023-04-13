/**
 * Tests.
 */

import { Role } from './role';
import { Session } from './session.js';

describe('isValid', () => {
  test('returns false if expiration date is in the past', async () => {
    const session = new Session({
      accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
      role: new Role('Foobiz', 'arn:aws:iam::123456789:role/Foobiz', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
      expiresAt: new Date('2020-04-19T10:32:19.000Z'),
      sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
      samlAssertion: 'T2NjdXB5IE1hcnMK'
    });

    expect(session.isValid()).toBeFalsy();
  });

  test('returns true if expiration date is in the future', async () => {
    const session = new Session({
      accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
      role: new Role('Foobiz', 'arn:aws:iam::123456789:role/Foobiz', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
      expiresAt: new Date(`${new Date().getFullYear() + 1}-04-19T10:32:19.000Z`),
      sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
      samlAssertion: 'T2NjdXB5IE1hcnMK'
    });

    expect(session.isValid()).toBeTruthy();
  });
});

describe('toIni', () => {
  test('returns content as an ini-compatible structure', () => {
    const session = new Session({
      accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
      role: new Role('Foobiz', 'arn:aws:iam::123456789:role/Foobiz', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
      expiresAt: new Date('2020-04-19T10:32:19.000Z'),
      sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
      samlAssertion: 'T2NjdXB5IE1hcnMK'
    });

    expect(session.toIni('test')).toEqual({
      aws_access_key_id: 'AAAAAABBBBBBCCCCCCDDDDDD',
      aws_role_arn: 'arn:aws:iam::123456789:role/Foobiz',
      aws_role_name: 'Foobiz',
      aws_role_principal_arn: 'arn:aws:iam::123456789:saml-provider/GSuite',
      aws_secret_access_key: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
      aws_session_expiration: '2020-04-19T10:32:19.000Z',
      aws_session_token: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
      aws_saml_assertion: 'T2NjdXB5IE1hcnMK'
    });
  });
});

describe('toJSON', () => {
  test('returns content as JSON', () => {
    const session = new Session({
      accessKeyId: 'AAAAAABBBBBBCCCCCCDDDDDD',
      role: new Role('Foobiz', 'arn:aws:iam::123456789:role/Foobiz', 'arn:aws:iam::123456789:saml-provider/GSuite'),
      secretAccessKey: '0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4',
      expiresAt: new Date('2020-04-19T10:32:19.000Z'),
      sessionToken: 'DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB',
      samlAssertion: 'T2NjdXB5IE1hcnMK'
    });

    expect(session.toJSON()).toEqual(`{"Version":1,"AccessKeyId":"AAAAAABBBBBBCCCCCCDDDDDD","SecretAccessKey":"0nKJNoiu9oSJBjkb+aDvVVVvvvB+ErF33r4","SessionToken":"DMMDnnnnKAkjSJi///////oiuISHJbMNBMNjkhkbljkJHGJGUGALJBjbjksbKLJHlOOKmmNAhhB","Expiration":"2020-04-19T10:32:19.000Z"}`);
  });
});
