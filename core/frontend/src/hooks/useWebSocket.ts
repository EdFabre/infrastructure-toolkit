import { useEffect, useRef, useState, useCallback } from 'react';

interface UseWebSocketOptions {
  onMessage?: (data: any) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
}

export function useWebSocket(url: string, options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    autoReconnect = true,
    reconnectInterval = 5000,
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();

  const connect = useCallback(() => {
    try {
      // Convert http/https to ws/wss
      const wsUrl = url.replace(/^http/, 'ws');
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log(`WebSocket connected: ${wsUrl}`);
        setIsConnected(true);
        onConnect?.();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
          onMessage?.(data);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        onError?.(error);
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setIsConnected(false);
        wsRef.current = null;
        onDisconnect?.();

        // Auto-reconnect
        if (autoReconnect) {
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log('Attempting to reconnect WebSocket...');
            connect();
          }, reconnectInterval);
        }
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('Error creating WebSocket:', error);
    }
  }, [url, onMessage, onConnect, onDisconnect, onError, autoReconnect, reconnectInterval]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const send = useCallback((data: any) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    } else {
      console.warn('WebSocket is not connected');
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    isConnected,
    lastMessage,
    send,
    disconnect,
    reconnect: connect,
  };
}

// Hook for real-time performance metrics
export function useMetricsWebSocket() {
  const [metrics, setMetrics] = useState<any>(null);

  const { isConnected, send } = useWebSocket('http://localhost:8000/api/ws/metrics', {
    onMessage: (data) => {
      if (data.type === 'metrics') {
        setMetrics(data.data);
      }
    },
  });

  const refresh = useCallback(() => {
    send({ action: 'refresh' });
  }, [send]);

  return { metrics, isConnected, refresh };
}

// Hook for real-time log streaming
export function useLogsWebSocket(server: string) {
  const [logs, setLogs] = useState<string>('');
  const [containers, setContainers] = useState<any[]>([]);

  const { isConnected, send } = useWebSocket(`http://localhost:8000/api/ws/logs/${server}`, {
    onMessage: (data) => {
      if (data.type === 'logs') {
        setLogs(data.logs || data.message);
      } else if (data.type === 'containers') {
        setContainers(data.containers);
      }
    },
  });

  const getLogs = useCallback((container: string, tail: number = 100) => {
    send({ action: 'get_logs', container, tail });
  }, [send]);

  const listContainers = useCallback(() => {
    send({ action: 'list_containers' });
  }, [send]);

  return { logs, containers, isConnected, getLogs, listContainers };
}

// Hook for real-time network monitoring
export function useNetworkWebSocket() {
  const [networkData, setNetworkData] = useState<any>(null);

  const { isConnected, send } = useWebSocket('http://localhost:8000/api/ws/network', {
    onMessage: (data) => {
      if (data.type === 'network') {
        setNetworkData(data.data);
      }
    },
  });

  const refresh = useCallback(() => {
    send({ action: 'refresh' });
  }, [send]);

  return { networkData, isConnected, refresh };
}
