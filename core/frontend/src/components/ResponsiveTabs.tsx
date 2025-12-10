import React from 'react';
import { LucideIcon } from 'lucide-react';

interface Tab {
  id: string;
  label: string;
  icon: LucideIcon;
}

interface ResponsiveTabsProps {
  tabs: Tab[];
  activeTab: string;
  onChange: (id: string) => void;
}

export const ResponsiveTabs: React.FC<ResponsiveTabsProps> = ({ tabs, activeTab, onChange }) => (
  <div className="flex gap-1 bg-slate-800 rounded-lg p-1 w-fit">
    {tabs.map((tab) => (
      <button
        key={tab.id}
        onClick={() => onChange(tab.id)}
        className={`flex items-center gap-2 px-3 py-2 rounded-md transition-colors ${
          activeTab === tab.id
            ? 'bg-primary-600 text-white'
            : 'text-slate-400 hover:text-white'
        }`}
        title={tab.label}
      >
        <tab.icon className="h-4 w-4 flex-shrink-0" />
        <span className="hidden sm:inline">{tab.label}</span>
      </button>
    ))}
  </div>
);
