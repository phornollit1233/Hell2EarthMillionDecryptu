package million.h2e.phornollit;

public interface JulesEncryptionEngine
{
	byte[] encrypt(String key, byte[] data, int offset, int dataSize);
	byte[] encrypt(byte[] key, byte[] data, int offset, int dataSize);
	byte[] decrypt(String key, byte[] data, int offset, int dataSize);
	byte[] decrypt(byte[] key, byte[] data, int offset, int dataSize);
}
