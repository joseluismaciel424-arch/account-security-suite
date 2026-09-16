import './globals.css';

export const metadata = {
  title: 'Account Security Suite',
  description: 'Protect your accounts, monitor security and detect suspicious activity',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
