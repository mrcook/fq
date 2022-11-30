def _apple_bookmark_torepr:
  def _f:
    ( if .type == "String" then .data | tovalue
      elif .type == "data" then .data | tovalue
      elif .type == "byte" then .data | tovalue
      elif .type == "short" then .data | tovalue
      elif .type == "Int" then .data | tovalue
      elif .type == "long" then .data | tovalue
      elif .type == "float" then .data | tovalue
      elif .type == "double" then .data | tovalue
      elif .type == "date" then .data | tovalue
      elif .type == "boolean_false" then false
      elif .type == "boolean_true" then true
      elif .type == "array" then 
        ( .data
        | map(.record | _f)
        )
      elif .type == "dictionary" then
        ( .data
        | map({key: (.key | _f), value: (.value | _f)})
        | from_entries
        )
      elif .type == "uuid" then .data | tovalue
      elif .type == "url" then .data | tovalue
      elif .type == "relative_url" then
        .data | map(.record.data)
      end
    );
  ( .bookmark_entries
  | map({key: (.key_string?.record.data // .key|tostring), value: (.record | _f)})
  | from_entries
  );


