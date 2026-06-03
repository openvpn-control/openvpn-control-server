export type SettingsFieldType = "number" | "select" | "text" | "textarea" | "checkbox";

export interface SelectOption {
  value: string;
  label: string;
}

export interface SettingsFieldMeta {
  key: string;
  label: string;
  description: string;
  type: SettingsFieldType;
  placeholder?: string;
  options?: SelectOption[];
}
