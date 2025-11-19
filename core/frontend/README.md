# Infrastructure Toolkit Frontend

React-based web dashboard for infrastructure monitoring and management.

## Features

- **Performance Monitoring**: Real-time server health dashboard with CPU, memory, and disk metrics
- **Network Management**: UniFi network monitoring (networks, WiFi, devices, clients)
- **Docker Management**: Container monitoring across multiple servers
- **Cloudflare Integration**: Tunnel hostname management
- **Pterodactyl Integration**: Game server monitoring

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **TanStack Query** - Data fetching and caching
- **React Router** - Routing
- **Tailwind CSS** - Styling
- **Recharts** - Data visualization
- **Lucide React** - Icons

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Type checking
npm run type-check

# Linting
npm run lint
```

The development server will start at `http://localhost:5173` with API proxy to `http://localhost:8000`.

## Project Structure

```
src/
├── components/      # Reusable UI components
│   ├── ServerCard.tsx
│   └── StatusBadge.tsx
├── hooks/          # Custom React hooks
│   ├── usePerformance.ts
│   ├── useNetwork.ts
│   └── useDocker.ts
├── pages/          # Page components
│   └── Dashboard.tsx
├── services/       # API client
│   └── api.ts
├── types/          # TypeScript types
│   └── api.ts
├── App.tsx         # Root component
├── main.tsx        # Entry point
└── index.css       # Global styles
```

## API Integration

The frontend connects to the FastAPI backend at `/api/*`:

- `/api/perf/*` - Performance monitoring
- `/api/net/*` - Network monitoring
- `/api/docker/*` - Docker management
- `/api/cloudflare/*` - Cloudflare tunnel management
- `/api/pterodactyl/*` - Game server monitoring

## Environment

Development environment uses Vite proxy to forward `/api/*` requests to the backend server.

For production, configure Nginx to serve the frontend and proxy API requests to the backend.
