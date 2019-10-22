import { exists as pathExists } from "fs";

export function doesFileExist(pathname: string): Promise<boolean> {
  return new Promise(resolve => {
    pathExists(pathname, exists => {
      resolve(exists);
    });
  });
}
