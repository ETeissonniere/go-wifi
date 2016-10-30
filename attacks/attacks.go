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

package attacks

import (
	"os"
	"time"
)

// To keep track of runned attacks
type Attack struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Running bool   `json:"running"`
	Started string `json:"started at"`
	Stopped string `json:"stopped at"`
	process *os.Process
}

// Quick hack to edit process
func (a *Attack) Init(proc *os.Process) {
	a.process = proc
}

func (a *Attack) Stop() error {
	err := a.process.Kill()
	if err != nil {
		return err
	}

	a.Running = false
	a.Stopped = time.Now().String()

	return nil
}
