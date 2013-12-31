package org.cryptosis.io;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Callback interface that supports arbitrary processing of data chunks read from an input stream.
 *
 * @author Marvin S. Addison
 */
public interface ChunkHandler
{
  /**
   * Processes the given chunk of data and writes it to the output stream.
   *
   * @param  input  Chunk of input data to process.
   * @param  offset  Offset into input array where data to process starts.
   * @param  count  Number of bytes of input data to process.
   * @param  output  Output stream where processed data is written.
   *
   * @throws  IOException  On IO errors.
   */
  void handle(byte[] input, int offset, int count, OutputStream output) throws IOException;
}
