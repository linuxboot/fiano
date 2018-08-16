# Visitor Prototype

Synopsis:

    utk BIOS OPERATIONS...

Examples:

    # Dump everything to JSON:
    utk winterfell.rom json

    # Dump a single file to JSON (using regex):
    utk winterfell.rom find Shell

    # Dump GUIDs and sizes to a compact table:
    utk winterfell.rom table

    # Extract everything into a directory:
    utk winterfell.rom extract winterfell/

    # Re-assemble the directory into an image:
    utk winterfell/ save winterfell2.rom

    # Remove two files by their GUID and replace shell with Linux:
    utk winterfell.rom \
      remove 12345678-9abc-def0-1234-567890abcdef \
      remove 23830293-3029-3823-0922-328328330939 \
      replace_pe32 Shell linux.efi \
      save winterfell2.rom

Operations:

- `json`: Dump the entire parsed image (excluding binary data) as JSON to
  stdout.
- `table`: Dump GUIDs and sizes to a compact table. This is only for human
  consumption and the format may change without notice.
- `find (GUID|NAME)`: Dump the JSON of a file. The file is found by a regex
  match to its GUID or name in the UI section. If the number of found files is
  unequal to one, the operation is still performed, but the exit status is 1.
- `remove (GUID|NAME)`: Remove the first file which matches the given GUID or
  NAME. The same matching rules and exit status are used as `find`.
- `replace (GUID|NAME) FILE`: Replace the first file which matches the given
  GUID or NAME with the contents of FILE. The same matching rules and exit
  status are used as `find`.
- `save FILE`: Save the current state of the image to the give file. Remember
  that operations are applied left-to-right, so only the operations to the left
  are included in the new image.
- `extract DIR`: Extract the BIOS to the given directory. Remember that
  operations are applied left-to-right, so only the operations to the left are
  included in the new image.
