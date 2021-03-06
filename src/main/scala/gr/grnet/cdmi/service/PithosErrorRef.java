/*
 * Copyright (C) 2010-2014 GRNET S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package gr.grnet.cdmi.service;

/**
 * @author Christos KK Loverdos <loverdos@gmail.com>
 */
public enum PithosErrorRef implements IErrorRef {
    // Pithos backend bad requests
    PBR001,
    PBR002,
    PBR003,
    PBR004,
    PBR005,
    PBR006,
    PBR007,
    PBR008,
    PBR009,

    // Pithos backend internal server errors
    PIE001,
    PIE002,
    PIE003,
    PIE004,
    PIE005,
    PIE006,
    PIE007,
    PIE008,
    PIE009,
    PIE010,
    PIE011,
    PIE012,
}
