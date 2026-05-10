import React, { useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Modal } from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { Ionicons } from '@expo/vector-icons';
import { Colors } from '../theme/colors';

export default function CredentialCard({ credential }) {
  const [showQR, setShowQR] = useState(false);
  const title = credential.type.replace(/_/g, ' ');

  // FIX: The QR code must encode the full credential object (including signature, userId, issuedAt)
  // exactly as stored — which is now the complete signed shape from the server.
  const qrDataString = JSON.stringify(credential);

  return (
    <>
      <TouchableOpacity style={styles.card} activeOpacity={0.9} onPress={() => setShowQR(true)}>
        <View style={styles.cardHeader}>
          <Text style={styles.cardTitle}>{title}</Text>
          <Ionicons name="shield-checkmark" color={Colors.success} size={20} />
        </View>
        <View style={styles.payloadContainer}>
          {Object.entries(credential.payload).map(([key, value]) => (
            <View key={key} style={styles.row}>
              <Text style={styles.label}>{key.toUpperCase()}</Text>
              <Text style={styles.value}>{value}</Text>
            </View>
          ))}
        </View>
        <View style={styles.footer}>
          <Text style={styles.issuedText}>Issued: {new Date(credential.issuedAt).toLocaleDateString()}</Text>
          <Text style={styles.tapPrompt}>Tap to reveal QR</Text>
        </View>
      </TouchableOpacity>

      <Modal visible={showQR} animationType="slide" presentationStyle="pageSheet">
        <View style={styles.modalContainer}>
          <TouchableOpacity style={styles.closeBtn} onPress={() => setShowQR(false)}>
            <Ionicons name="close" color={Colors.text} size={32} />
          </TouchableOpacity>
          <Text style={styles.modalTitle}>{title}</Text>
          <Text style={styles.modalSubtitle}>Present this code to the verifier</Text>
          <View style={styles.qrWrapper}>
            <QRCode
              value={qrDataString}
              size={250}
              color={Colors.text}
              backgroundColor={Colors.surface}
              quietZone={10}
            />
          </View>
          <View style={styles.securityBadge}>
            <Ionicons name="shield-checkmark" color={Colors.success} size={16} />
            <Text style={styles.securityText}>Cryptographically Signed (Ed25519)</Text>
          </View>
        </View>
      </Modal>
    </>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: Colors.surface, borderRadius: 16, padding: 20, marginBottom: 16, borderWidth: 1, borderColor: Colors.border, elevation: 2 },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  cardTitle: { fontSize: 18, fontWeight: '700', color: Colors.primary },
  payloadContainer: { backgroundColor: Colors.background, borderRadius: 8, padding: 12, marginBottom: 16 },
  row: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 },
  label: { fontSize: 11, color: Colors.muted, fontWeight: '600', letterSpacing: 0.5 },
  value: { fontSize: 13, color: Colors.text, fontWeight: '500', maxWidth: '60%', textAlign: 'right' },
  footer: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  issuedText: { fontSize: 12, color: Colors.muted },
  tapPrompt: { fontSize: 12, color: Colors.primary, fontWeight: '600' },
  modalContainer: { flex: 1, backgroundColor: Colors.background, alignItems: 'center', paddingTop: 60 },
  closeBtn: { position: 'absolute', top: 20, right: 20, padding: 10 },
  modalTitle: { fontSize: 24, fontWeight: 'bold', color: Colors.text, marginTop: 40 },
  modalSubtitle: { fontSize: 15, color: Colors.muted, marginTop: 8, marginBottom: 40 },
  qrWrapper: { padding: 20, backgroundColor: Colors.surface, borderRadius: 24, elevation: 5 },
  securityBadge: { flexDirection: 'row', alignItems: 'center', marginTop: 40, backgroundColor: '#ECFDF5', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 20 },
  securityText: { color: Colors.success, fontSize: 13, fontWeight: '600', marginLeft: 6 }
});