export const APP_NAME = 'Account Security Suite';
export const API_HEALTH_MESSAGE = 'System healthy and monitoring active.';

export type AccountStatus = 'secure' | 'needs-attention' | 'critical';

export type AccountSummary = {
  id: string;
  provider: string;
  status: AccountStatus;
  lastCheckedAt: string;
};
