#pragma once

#ifndef PROCESSWATCHER_H
#define PROCESSWATCHER_H

namespace GarudaHS {
    /**
     * Scan running processes for blacklisted cheat tools
     * If found, will terminate the game process
     */
    void ScanProcess();

    /**
     * Terminate game if cheat is detected
     */
    void TerminateGameIfCheatFound();
}

#endif // PROCESSWATCHER_H