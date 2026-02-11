import { useEffect, useState } from "react";
import { Button, FormField, Panel, inputClassName } from "./ui";

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
  const [draftJwt, setDraftJwt] = useState(jwt);
  const [draftTenantId, setDraftTenantId] = useState(tenantId);

  useEffect(() => {
    setDraftJwt(jwt);
    setDraftTenantId(tenantId);
  }, [jwt, tenantId]);

  return (
    <Panel title="Dev Access Panel">
      <div className="space-y-3">
        <FormField label="JWT">
          <input className={inputClassName} value={draftJwt} onChange={(e) => setDraftJwt(e.target.value)} placeholder="Paste bearer token" />
        </FormField>
        <FormField label="Tenant ID">
          <input className={inputClassName} value={draftTenantId} onChange={(e) => setDraftTenantId(e.target.value)} placeholder="Tenant UUID" />
        </FormField>
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={() => {
              setJwt(draftJwt.trim());
              setTenantId(draftTenantId.trim());
            }}
          >
            Set Credentials
          </Button>
          <Button
            onClick={() => {
              setDraftJwt("");
              setDraftTenantId("");
              setJwt("");
              setTenantId("");
            }}
          >
            Clear
          </Button>
        </div>
      </div>
    </Panel>
  );
}
