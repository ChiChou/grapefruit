import ObjC from "frida-objc-bridge";
import { BaseMessage, bt } from "@/common/hooks/context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "biometric";
  policy?: string;
  reason?: string;
  bypassed: boolean;
}

const LA_POLICIES: Record<number, string> = {
  1: "DeviceOwnerAuthenticationWithBiometrics",
  2: "DeviceOwnerAuthentication",
  3: "DeviceOwnerAuthenticationWithWatch",
  4: "DeviceOwnerAuthenticationWithBiometricsOrWatch",
};

/**
 * Bypass Touch ID / Face ID authentication by hooking LAContext
 */
export function bypass() {
  if (!ObjC.available) return [];

  const hooks: InvocationListener[] = [];
  const LAContext = ObjC.classes.LAContext;
  if (!LAContext) return [];

  // Hook evaluatePolicy:localizedReason:reply:
  const evaluatePolicy = LAContext["- evaluatePolicy:localizedReason:reply:"];
  if (evaluatePolicy) {
    hooks.push(
      Interceptor.attach(evaluatePolicy.implementation, {
        onEnter(args) {
          this.policy = args[2].toInt32();
          this.reason = new ObjC.Object(args[3]).toString();

          // Get the reply block and replace its implementation
          const block = new ObjC.Block(args[4]);
          const origImpl = block.implementation;

          block.implementation = function (
            _success: boolean,
            _error: NativePointer,
          ) {
            // Always call with success=true, error=null
            return origImpl(true, NULL);
          };
        },
        onLeave() {
          const policyStr =
            LA_POLICIES[this.policy] || `Unknown(${this.policy})`;
          send({
            subject: "hook",
            category: "biometric",
            symbol: "-[LAContext evaluatePolicy:localizedReason:reply:]",
            dir: "leave",
            line: `evaluatePolicy(${policyStr}) → BYPASSED`,
            policy: policyStr,
            reason: this.reason,
            bypassed: true,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook canEvaluatePolicy:error: to always return YES
  const canEvaluatePolicy = LAContext["- canEvaluatePolicy:error:"];
  if (canEvaluatePolicy) {
    hooks.push(
      Interceptor.attach(canEvaluatePolicy.implementation, {
        onEnter(args) {
          this.policy = args[2].toInt32();
          // Clear the error pointer if provided
          if (!args[3].isNull()) {
            args[3].writePointer(NULL);
          }
        },
        onLeave(retval) {
          // Always return YES (1)
          retval.replace(ptr(1));

          const policyStr =
            LA_POLICIES[this.policy] || `Unknown(${this.policy})`;
          send({
            subject: "hook",
            category: "biometric",
            symbol: "-[LAContext canEvaluatePolicy:error:]",
            dir: "leave",
            line: `canEvaluatePolicy(${policyStr}) → YES (forced)`,
            policy: policyStr,
            bypassed: true,
          } as Message);
        },
      }),
    );
  }

  // Hook evaluateAccessControl:operation:localizedReason:reply:
  const evaluateAccessControl =
    LAContext["- evaluateAccessControl:operation:localizedReason:reply:"];
  if (evaluateAccessControl) {
    hooks.push(
      Interceptor.attach(evaluateAccessControl.implementation, {
        onEnter(args) {
          this.reason = new ObjC.Object(args[4]).toString();

          // Get the reply block and replace its implementation
          const block = new ObjC.Block(args[5]);
          const origImpl = block.implementation;

          block.implementation = function (
            _success: boolean,
            _error: NativePointer,
          ) {
            return origImpl(true, NULL);
          };
        },
        onLeave() {
          send({
            subject: "hook",
            category: "biometric",
            symbol:
              "-[LAContext evaluateAccessControl:operation:localizedReason:reply:]",
            dir: "leave",
            line: `evaluateAccessControl(...) → BYPASSED`,
            reason: this.reason,
            bypassed: true,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  return hooks;
}
