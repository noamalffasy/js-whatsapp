import fs from "fs";

export function doesFileExist(pathname: string): Promise<boolean> {
  return new Promise((resolve) => {
    fs.access(pathname, fs.constants.R_OK, (err) => {
      resolve(!err);
    });
  });
}

export function readFile(pathname: string): Promise<string> {
  return new Promise((resolve, reject) => {
    fs.readFile(pathname, { encoding: "utf8" }, (err, data) => {
      if (err) reject(err);
      resolve(data);
    });
  });
}
