import { SQL } from "bun"

const sql = new SQL({
  bigint: true,
  connection: {
    clientFoundRows: true
  },
  prepare: true
})

export default sql
