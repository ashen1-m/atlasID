import React, { useState, useCallback } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Alert } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { useFocusEffect } from '@react-navigation/native';
import { WalletService } from '../services/WalletService';
import { Colors } from '../theme/colors';
import { Ionicons } from '@expo/vector-icons';

export default function VerifierScreen() {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [cachedKey, setCachedKey] = useState(null);

  useFocusEffect(
    useCallback(() => {
      const loadKey = async () => {
        const key = await WalletService.getCachedPublicKey();
        setCachedKey(key);
      };
      
      loadKey();
      setScanned(false);
    }, [])
  );

  const handleBarCodeScanned = ({ type, data }) => {
    setScanned(true);
    
    try {
      if (!cachedKey) {
        Alert.alert("Keys Missing", "You must sync the public key in the Wallet tab first.");
        return;
      }

      const qrPayload = JSON.parse(data);

      // FIX: Log the parsed QR payload so you can confirm all fields are present during testing
      console.log("QR Payload received:", JSON.stringify(qrPayload, null, 2));
      console.log("Fields present — id:", !!qrPayload.id, "userId:", !!qrPayload.userId,
        "type:", !!qrPayload.type, "payload:", !!qrPayload.payload,
        "issuedAt:", !!qrPayload.issuedAt, "signature:", !!qrPayload.signature);

      const isValid = WalletService.verifyOffline(qrPayload, cachedKey);

      if (isValid) {
        Alert.alert(
          "✅ VERIFIED AUTHENTIC", 
          `Name: ${qrPayload.payload.name}\nOrigin: ${qrPayload.payload.origin}\nType: ${qrPayload.type}`
        );
      } else {
        Alert.alert(
          "❌ VERIFICATION FAILED",
          "This credential's signature is invalid or the data was tampered with."
        );
      }
    } catch (error) {
      console.error("Scan Error:", error);
      Alert.alert("Invalid Format", "This is not a recognized Atlas ID QR code.");
    }
  };

  if (!permission) {
    return <View style={styles.container}><Text style={styles.text}>Loading camera...</Text></View>;
  }

  if (!permission.granted) {
    return (
      <View style={styles.container}>
        <Text style={styles.text}>We need your permission to show the camera</Text>
        <TouchableOpacity style={styles.btn} onPress={requestPermission}>
          <Text style={styles.btnText}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <CameraView 
        style={StyleSheet.absoluteFillObject} 
        onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
      />
      
      <View style={styles.overlay}>
        <View style={styles.scanBox} />
        
        <View style={styles.statusContainer}>
          {!cachedKey ? (
            <Text style={styles.warningText}>Offline keys missing. Sync required.</Text>
          ) : (
            <Text style={styles.successText}>✅ Cryptographic Keys Loaded</Text>
          )}
        </View>

        {scanned && (
          <TouchableOpacity style={styles.scanAgainBtn} onPress={() => setScanned(false)}>
            <Ionicons name="scan-outline" size={24} color="#fff" />
            <Text style={styles.scanAgainText}>Tap to Scan Again</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.background, justifyContent: 'center', alignItems: 'center' },
  text: { color: Colors.text, fontSize: 16, marginBottom: 20 },
  btn: { backgroundColor: Colors.primary, padding: 12, borderRadius: 8 },
  btnText: { color: '#fff', fontWeight: 'bold' },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.4)',
  },
  scanBox: {
    width: 250,
    height: 250,
    borderWidth: 2,
    borderColor: Colors.primary,
    backgroundColor: 'transparent',
    borderRadius: 16,
  },
  statusContainer: {
    position: 'absolute',
    bottom: 120,
    backgroundColor: Colors.surface,
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 20,
  },
  warningText: { color: Colors.danger, fontWeight: 'bold', fontSize: 14 },
  successText: { color: Colors.success, fontWeight: 'bold', fontSize: 14 },
  scanAgainBtn: {
    position: 'absolute',
    bottom: 50,
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.primary,
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 30,
    elevation: 5,
  },
  scanAgainText: { color: '#fff', fontSize: 16, fontWeight: 'bold', marginLeft: 8 }
});