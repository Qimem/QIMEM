import { Button, FormField, Panel } from "./ui";

export function DevAccessPanel({
  jwt,
  tenantId,
  setJwt,
  setTenantId,
}: {
  jwt: string;
  tenantId: string;
  setJwt: (value: string) => void;
  setTenantId: (value: string) => void;
}) {
  return (
    <Panel title="Dev Access Panel">
      <div className="space-y-3">
        <FormField label="JWT">
          <input className="w-full rounded-md border border-base-border bg-base-bg p-2 text-sm" value={jwt} onChange={(e) => setJwt(e.target.value)} />
        </FormField>
        <FormField label="Tenant ID">
          <input className="w-full rounded-md border border-base-border bg-base-bg p-2 text-sm" value={tenantId} onChange={(e) => setTenantId(e.target.value)} />
        </FormField>
        <Button>Set Credentials</Button>
      </div>
    </Panel>
  );
}
