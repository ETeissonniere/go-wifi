/*

   Copyright (C) 2016  DeveloppSoft <developpsoft@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

*/

package captures

import (
	"os/exec"
	"strings"
)

// Capture struct: handle airodump captures to crack them with aircrack-ng
type (
	Capture struct {
		Key       string `json:"key"`
		Target    Target `json:"target"`
		Handshake bool   `json:"handshake captured"`
		IVs       int    `json:"ivs"`
		Cracking  bool   `json:"trying to crack"`
		pcap_file string
	}

	Target struct {
		Bssid string `json:"bssid"`
		Essid string `json:"essid"`
		// WPA, WPA2, WEP, OPN
		Privacy string `json:"privacy"`
	}
)

// Build the struct thanks to the dir (with .pcap and .csv) path
func (c *Capture) Init(path_to_captures string, privacy string, bssid string, essid string) {
	c.pcap_file = path_to_captures + "go-wifi-01.cap"

	// Fill the struct!
	c.Target.Bssid = bssid
	c.Target.Essid = essid
	c.Target.Privacy = privacy

	/*
	// Check if we have an Handshake
	if privacy == "WPA" || privacy == "WPA2" {
		c.checkForHandshake()
	}

	c.getIVs()
	*/
}

// Return succesfull key
func (c *Capture) TryKeys(...string) string {
	return nil
}

// Return success, ascii key
func (c *Capture) AttemptToCrack() (bool, string) {
	return false, nil
}
/*
func (c *Capture) checkForHandshake() {
	// Thank you wifite (l. 2478, has_handshake_aircrack)
	cmd := exec.Command(`echo "" | aircrack-ng -a 2 -w - -b ` + c.Target.Bssid + " " + c.pcap_file)

	ouptut, err := cmd.Output()

	if err == nil {
		if strings.Contains(string(ouptut), "Passphrase not in dictionary") {
			c.Handshake = true
		} else {
			c.Handshake = false
		}
	}
}

func (c *Capture) getIVs() {

}
*/