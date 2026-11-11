// Session context and the sign-out action shared by the header and the settings page.

import { createContext, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { auth, clearSession } from './api';

export const SessionContext = createContext(false);

export function useAuthenticated(): boolean {
  return useContext(SessionContext);
}

/** Sign out: revoke the session server-side, then drop local tokens even if that call fails. */
export function useSignOut(): () => Promise<void> {
  const navigate = useNavigate();
  return async () => {
    try {
      await auth.logout();
    } catch (error) {
      console.warn('logout failed; clearing local session anyway', error);
    }
    clearSession();
    navigate('/login', { replace: true });
  };
}
