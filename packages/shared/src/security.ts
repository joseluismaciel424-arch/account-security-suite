import { APP_NAME } from '@account-security-suite/shared';

export type SecurityFactor = {
  id: string;
  name: string;
  enabled: boolean;
  status: 'active' | 'needs-attention' | 'disabled';
  description: string;
};

export const securityFactors: SecurityFactor[] = [
  {
    id: 'mfa',
    name: 'Multi-factor authentication',
    enabled: true,
    status: 'active',
    description: 'Requires a second verification step when signing in.',
  },
  {
    id: 'passkeys',
    name: 'Passkeys',
    enabled: false,
    status: 'needs-attention',
    description: 'Use phishing-resistant sign-in for higher protection.',
  },
  {
    id: 'session-monitoring',
    name: 'Session monitoring',
    enabled: true,
    status: 'active',
    description: 'Track suspicious login events across your accounts.',
  },
  {
    id: 'recovery-email-check',
    name: 'Recovery email validation',
    enabled: true,
    status: 'active',
    description: 'Check that your recovery email is valid and reachable.',
  },
  {
    id: 'device-recognition',
    name: 'Device recognition',
    enabled: true,
    status: 'active',
    description: 'Detect and flag unrecognized devices or locations.',
  },
  {
    id: 'breach-monitoring',
    name: 'Breach monitoring',
    enabled: true,
    status: 'active',
    description: 'Watch for public breaches involving your email or credentials.',
  },
];

export const buildSecurityOverview = () => ({
  app: APP_NAME,
  protectionLevel: 'High',
  riskLevel: 'Low',
  factors: securityFactors,
  totalEnabled: securityFactors.filter((factor) => factor.enabled).length,
  totalNeedsAttention: securityFactors.filter((factor) => factor.status === 'needs-attention').length,
});
