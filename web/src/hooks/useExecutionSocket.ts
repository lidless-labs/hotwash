/**
 * WebSocket hook for live execution updates.
 * Gracefully degrades if WebSocket is unavailable.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { API_BASE_URL } from '../api/client';
import { liveSocketUrl, requestLiveTicket } from '../api/auth';

const WS_BASE = (() => {
  try {
    return API_BASE_URL.replace(/^http/, 'ws');
  } catch {
    return `ws://${window.location.hostname}:8000`;
  }
})();

export interface ExecutionEvent {
  type: string;
  timestamp: string;
  data?: any;
}

export function useExecutionSocket(executionId: string | undefined) {
  const [lastEvent, setLastEvent] = useState<ExecutionEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  // Bumped by every effect setup and cleanup. A connection attempt carries the
  // generation it started under and gives up when that no longer matches, so a
  // ticket request that resolves after cleanup (an execution change, or the
  // StrictMode setup/cleanup/setup cycle) cannot open a stale socket.
  const generationRef = useRef(0);

  const scheduleRetry = useCallback((connectAgain: () => void) => {
    const delay = Math.min(1000 * 2 ** retryRef.current, 30000);
    retryRef.current++;
    timerRef.current = setTimeout(connectAgain, delay);
  }, []);

  const connect = useCallback(
    async (generation: number) => {
      if (!executionId || generationRef.current !== generation) return;
      try {
        // The long-lived API key never appears in the socket URL. A short-lived
        // ticket, bound to this execution, is minted per connection attempt.
        const ticket = await requestLiveTicket(API_BASE_URL, executionId);
        if (generationRef.current !== generation) return;
        const ws = new WebSocket(liveSocketUrl(WS_BASE, executionId, ticket));
        wsRef.current = ws;

        ws.onopen = () => {
          setConnected(true);
          retryRef.current = 0;
        };

        ws.onmessage = (e) => {
          try {
            const event = JSON.parse(e.data) as ExecutionEvent;
            setLastEvent(event);
          } catch {}
        };

        ws.onclose = () => {
          setConnected(false);
          wsRef.current = null;
          scheduleRetry(() => connect(generation));
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch {
        setConnected(false);
        if (generationRef.current === generation) scheduleRetry(() => connect(generation));
      }
    },
    [executionId, scheduleRetry],
  );

  useEffect(() => {
    generationRef.current += 1;
    connect(generationRef.current);
    return () => {
      generationRef.current += 1;
      if (timerRef.current) clearTimeout(timerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
      setConnected(false);
    };
  }, [connect]);

  return { lastEvent, connected };
}
