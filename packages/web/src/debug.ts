declare const self: any;

export class Debug {

  public static get enabled() {
    return typeof self !== "undefined" && (self as any).PV_WEBCRYPTO_LINER_LOG;
  }

  public static log(message?: any, ...optionalParams: any[]): void;
  public static log(...args: any[]) {
    if (this.enabled) {
      console.log.apply(console, args);
    }
  }

  public static error(message?: any, ...optionalParams: any[]): void;
  public static error(...args: any[]) {
    if (this.enabled) {
      console.error.apply(console, args);
    }
  }

  public static info(message?: any, ...optionalParams: any[]): void;
  public static info(...args: any[]) {
    if (this.enabled) {
      console.info.apply(console, args);
    }
  }

  public static warn(message?: any, ...optionalParams: any[]): void;
  public static warn(...args: any[]) {
    if (this.enabled) {
      console.warn.apply(console, args);
    }
  }

  public static trace(message?: any, ...optionalParams: any[]): void;
  public static trace(...args: any[]) {
    if (this.enabled) {
      console.trace.apply(console, args);
    }
  }

}
