declare module '@novnc/novnc/lib/rfb.js' {
  export default class RFB {
    constructor(target: HTMLElement, url: string, options?: { shared?: boolean });
    scaleViewport: boolean;
    resizeSession: boolean;
    background: string;
    addEventListener(type: string, callback: (event: Event) => void): void;
    disconnect(): void;
    sendCredentials(credentials: { username?: string; password?: string; target?: string }): void;
  }
}
