import React, { useEffect, useState } from 'react';
import { Download, WifiOff } from 'lucide-react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
}

export function usePWAInstall() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIOS, setIsIOS] = useState(false);

  useEffect(() => {
    const isStandalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as unknown as { standalone?: boolean }).standalone === true;
    setIsInstalled(isStandalone);

    const userAgent = window.navigator.userAgent.toLowerCase();
    setIsIOS(/iphone|ipad|ipod/.test(userAgent));

    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };

    const handleAppInstalled = () => {
      setIsInstalled(true);
      setDeferredPrompt(null);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  const install = async () => {
    if (!deferredPrompt) return false;
    await deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      setIsInstalled(true);
      setDeferredPrompt(null);
      return true;
    }
    return false;
  };

  return {
    isInstallable: Boolean(deferredPrompt),
    isInstalled,
    isIOS,
    install,
  };
}

export function useOnlineStatus() {
  const [isOnline, setIsOnline] = useState(
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return isOnline;
}

export const PWAInstallButton: React.FC = () => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);

  if (isInstalled) return null;

  if (isInstallable) {
    return (
      <button
        type="button"
        onClick={install}
        className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-teal-800 dark:text-[#2DD4BF] bg-teal-50 dark:bg-[#13282B] border border-teal-200 dark:border-[#2DD4BF]/35 hover:bg-teal-100 dark:hover:bg-[#173539] hover:shadow-[0_4px_14px_-4px_rgba(45,212,191,0.35)] rounded-lg whitespace-nowrap cursor-pointer"
      >
        <Download className="w-3.5 h-3.5" />
        <span>Install App</span>
      </button>
    );
  }

  if (isIOS) {
    return (
      <>
        <button
          type="button"
          onClick={() => setShowIOSGuide(true)}
          className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-[#131D23] border border-slate-300 dark:border-[#273B47] hover:bg-slate-50 dark:hover:bg-[#19262E] rounded-lg whitespace-nowrap cursor-pointer"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Install on iOS</span>
        </button>

        {showIOSGuide && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
            <div className="w-full max-w-sm rounded-xl bg-white dark:bg-[#0D1418] border border-slate-200 dark:border-[#1D2C35] p-6 shadow-xl space-y-3">
              <h3 className="text-base font-semibold text-slate-900 dark:text-[#F0F6FA]">
                Install on iPhone / iPad
              </h3>
              <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                1. Tap the <strong>Share</strong> icon in Safari.<br />
                2. Select <strong>Add to Home Screen</strong> to launch in standalone app mode.
              </p>
              <button
                type="button"
                onClick={() => setShowIOSGuide(false)}
                className="w-full rounded-lg bg-slate-100 dark:bg-[#131D23] hover:bg-slate-200 dark:hover:bg-[#1C2A32] py-2 text-xs font-medium text-slate-800 dark:text-slate-200 cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  return null;
};

export const OfflineIndicator: React.FC = () => {
  const isOnline = useOnlineStatus();
  if (isOnline) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex items-center gap-2 rounded-lg bg-amber-700 px-3.5 py-2 text-xs font-medium text-white shadow-lg print:hidden">
      <WifiOff className="w-3.5 h-3.5" />
      <span>Offline Mode — Local workspace cached</span>
    </div>
  );
};
