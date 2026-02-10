import { styleText } from "node:util"

import sql from "#src/lib/sql"


try {
  await sql.file("./src/lib/sql/setup.sql")
  console.log(styleText("magentaBright", "`/src/lib/sql/setup.sql` queries have been successfully executed."))
} catch(error) {
  console.error(error)
  console.warn("Error while executing SQL setup queries.")
}