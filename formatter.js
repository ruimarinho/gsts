
/**
 * Format output according to the requested output format.
 */

export async function format(content, format) {
  if (format === undefined) {
    return;
  }

  if (format !== 'json') {
    throw new Error(`Unsupported output format ${format}`);
  }

  process.stdout.write(content.toJSON());
}
