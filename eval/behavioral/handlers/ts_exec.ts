import { exec } from "child_process";

export async function runCommand(command: string): Promise<void> {
  exec(command);
}
