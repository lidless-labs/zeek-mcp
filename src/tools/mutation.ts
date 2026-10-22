export type MutationGate =
  | { allowed: true }
  | {
      allowed: false;
      response: {
        content: Array<{ type: "text"; text: string }>;
        isError: true;
      };
    };

// Match suricata-mcp: require operator opt-in and confirmation on every call.
export function checkMutationAllowed(
  allowMutation: boolean,
  args: { confirm?: boolean },
  action: string,
): MutationGate {
  if (!allowMutation) {
    return {
      allowed: false,
      response: {
        content: [{ type: "text", text: `Refusing to ${action}: mutating tools are disabled. Set ZEEK_ALLOW_MUTATION=1 in the server environment to enable them.` }],
        isError: true,
      },
    };
  }
  if (args.confirm !== true) {
    return {
      allowed: false,
      response: {
        content: [{ type: "text", text: `Refusing to ${action}: this operation changes state. Re-invoke with confirm: true to proceed.` }],
        isError: true,
      },
    };
  }
  return { allowed: true };
}
