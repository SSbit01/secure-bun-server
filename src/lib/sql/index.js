import { SQL } from "bun"

const sql = new SQL({
  bigint: true,
  prepare: true
})

export default sql
