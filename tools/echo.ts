/** Echoes back the input message */
export function echo(params: {
  /** Message to echo back */
  message: string;
}): Promise<any>;

/** Adds two numbers */
export function add(params: {
  /** First number */
  a: number;
  /** Second number */
  b: number;
}): Promise<any>;

/** Returns the current UTC time */
export function time(): Promise<any>;
