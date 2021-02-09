import fs from "fs";

export function doesFileExist(pathname: string): Promise<boolean> {
  return new Promise(resolve => {
    fs.access(pathname, fs.constants.R_OK, err => {
      resolve(!err);
    });
  });
}
