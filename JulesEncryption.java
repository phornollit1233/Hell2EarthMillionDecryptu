package million.h2e.phornollit;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.charset.Charset;

public class JulesEncryption implements JulesEncryptionEngine
{
	protected interface JulesEncryptionEngineAlgorithm
	{
		byte[] encrypt(byte[] data, int offset, int dataSize);
		byte[] decrypt(byte[] data, int offset, int dataSize);
	}
	protected class JulesEncryptionEngineAlgorithmImp implements JulesEncryptionEngineAlgorithm
	{
		private byte[] mKey;
		public JulesEncryptionEngineAlgorithmImp(byte[] key)
		{
			assert key != null;
			assert key.length > 0;
			
			mKey = key;
		}

		protected int flipBits(int v)
		{
			int flipped = 0;
			int[] bitMasks = new int[32];
			bitMasks[0] = 1;
			// sets all masks relative to its position
			// regarding index 0 bit sits in a highest portion
			// of a memory resistor, like
			// 0 1 2 3 4 5 6 7 ... 32
			// that might be the least significant bit first scheme.
			for(int i=1; i<32; i++)
			{
				// reminding the ah, binary set system multiplied by two
				// for jump up to move a bit to left, in left to right reading system.
				bitMasks[i] = bitMasks[i - 1] * 2;
			}
			
			for(int i=0; i<32; i++)
			{
				int value = v&bitMasks[i];
				// bit shift to left operator not present in Java.
				// why? lol
				value = value >>> i;
				// bit or to sum up results? lol
				flipped = flipped | value;
			}
			
			return flipped;
		}

		private final int UBYTE_MAX = 255;
		
		@Override
		public byte[] encrypt(byte[] data, int offset, int dataSize)
		{
			ByteBuffer buffer = ByteBuffer.allocate(dataSize * Integer.SIZE);
			buffer.order(ByteOrder.LITTLE_ENDIAN);
			
			IntBuffer ibuffer = buffer.asIntBuffer();
			
			int keySize = mKey.length;
			for(int i=0; i<dataSize; i++)
			{
				int e = data[i + offset];
				if( ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN )
				{
					// to little endian
					e = flipBits(e);
				}
				
				for(int j=0; j<keySize; j++)
				{
					if( j%2 == 0 )
					{
						e = e + mKey[j];
					}
					else
					{
						e = e * mKey[j];
					}
					
					if( e < 0 )
					{
						// will take a rest from the ring set for encryption.
						// (please, see set theory for details.)
						e = e % UBYTE_MAX;
						e = UBYTE_MAX + e;
					}

					e = e % UBYTE_MAX;
					
					buffer.put((byte) e);
				}
			}
			
			return buffer.array();
		}

		@Override
		public byte[] decrypt(byte[] data, int offset, int dataSize)
		{
			int keySize = mKey.length;
			// encrypted data supposed to be an little endian aligned encryption data.
			ByteBuffer buffer = ByteBuffer.wrap(data, offset, dataSize);
			for(int i=0; i<dataSize; i++)
			{
				// should not be confused with ByteBuffer.getInt function
				// that will read 4 bytes from the buffer.
				// using ByteBuffer.get to get one byte from the buffer.
				int e = buffer.get();

				for(int j=0; j<keySize; j++)
				{
					if( j%2 == 0 )
					{
						e = e - mKey[j];
					}
					else
					{
						e = e * mKey[j];
					}

					// gets a rest clipped to UBYTE_MAX for residue
					// (please, see mathematical set theory for details.)
					e = e % UBYTE_MAX;
					
					if( e > 0 )
					{
						// nothing to do
					}
					else
					{
						// will take a rest from the ring set for encryption.
						// (please, see set theory for details.)
						e = e % UBYTE_MAX;
						e = UBYTE_MAX + e;
					}
					
					buffer.put((byte) e);
				}
			}
			
			return buffer.array();
		}
	}
	
	protected void onError(Class<?> type, Object instance, String funcName, String errorMessage, int errorCode)
	{
		
	}
	
	@Override
	public final byte[] encrypt(String key, byte[] data, int offset, int dataSize)
	{
		Charset encoder = Charset.defaultCharset();
		ByteBuffer keyDataBuffer = encoder.encode(key);
		return encrypt(keyDataBuffer.array(), data, offset, dataSize);
	}

	@Override
	public byte[] encrypt(byte[] key, byte[] data, int offset, int dataSize)
	{
		byte[] keyData = key;
		JulesEncryptionEngineAlgorithm algo = new JulesEncryptionEngineAlgorithmImp(keyData);
		byte[] encrypted = algo.encrypt(data, offset, dataSize);
		if( null == encrypted )
		{
			onError(this.getClass(), this, "encrypt", "the algorithm doesn't produce encryption data. implementation name = " + algo.getClass().getCanonicalName(), 0);
			return null;
		}
		
		return encrypted;
	}

	@Override
	public byte[] decrypt(String key, byte[] data, int offset, int dataSize)
	{
		Charset encoder = Charset.defaultCharset();
		ByteBuffer keyDataBuffer = encoder.encode(key);
		return decrypt(keyDataBuffer.array(), data, offset, dataSize);
	}

	@Override
	public byte[] decrypt(byte[] key, byte[] data, int offset, int dataSize)
	{
		byte[] keyData = key;
		JulesEncryptionEngineAlgorithm algo = new JulesEncryptionEngineAlgorithmImp(keyData);
		byte[] encrypted = algo.decrypt(data, offset, dataSize);
		if( null == encrypted )
		{
			onError(this.getClass(), this, "decrypt", "the algorithm doesn't produce decryption data. implementation name = " + algo.getClass().getCanonicalName(), 0);
			return null;
		}
		
		return encrypted;
	}

}
