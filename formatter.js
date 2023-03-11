
/**
 * Format output according to the requested output format.
 */

export function format(content, format) {
  // If not format has been set via command line parameters or if the `none` format
  // has been explicity choosen, do not format or log output.
  if (!format || format === 'none') {
    return '';
  }

  if (format !== 'json') {
    throw new Error(`Unsupported output format ${format}`);
  }

  return content.toJSON();
}
