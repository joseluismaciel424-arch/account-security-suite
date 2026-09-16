export type SecurityRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type SecurityEvent = {
  id: string;
  userId: string;
  type: string;
  level: SecurityRiskLevel;
  title: string;
  description: string;
  createdAt: string;
  resolved: boolean;
};

export const securityEventTemplates = [
  {
    type: 'new-device-signin',
    level: 'medium',
    title: 'New device sign-in detected',
    description: 'A new device or browser attempted to sign in to your account.',
  },
  {
    type: 'password-changed',
    level: 'high',
    title: 'Password changed',
    description: 'A password change was detected for this account.',
  },
  {
    type: 'recovery-update',
    level: 'high',
    title: 'Recovery settings changed',
    description: 'Recovery options were updated and should be reviewed.',
  },
  {
    type: 'mfa-disabled',
    level: 'critical',
    title: 'MFA was disabled',
    description: 'Two-factor authentication was disabled. Re-enable it immediately.',
  },
];
