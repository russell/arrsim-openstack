;;; -*- Mode: Lisp; Syntax: COMMON-LISP; Base: 10 -*-

;; arrsim-openstack is a collection of openstack utilities
;; Copyright (C) 2012 Russell Sim <russell.sim@gmail.com>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(in-package :arrsim-openstack)

(defun calculate-rule-changes (&optional (group "development"))
  (flet ((make-cidr (ip)
           (concatenate 'string ip "/32")))
    (let* ((ips (mapcar #'make-cidr (vm-ips)))
           (changes (loop :for ip :in ips :collect (cons ip (list 'tcp 'udp)))))
      (dolist (rule (nova-secgroup-list-rules group))
        (let ((protocol (assoc-default 'protocol rule))
              (from-port (assoc-default 'from-port rule))
              (to-port (assoc-default 'to-port rule))
              (ip-range (assoc-default 'ip-range rule)))
          (when (and (equal from-port "1")
                     (equal to-port "65535")
                     (not (member ip-range ips :test #'string-equal)))
            (remove-security-rule group protocol from-port to-port ip-range))
          (let ((change (assoc ip-range changes :test #'string-equal)))
            (when (and change
                       (equal from-port "1")
                       (equal to-port "65535"))
              (rplacd change (remove (intern (string-upcase protocol)) (cdr change)))))))
      (dolist (rule changes)
        (let ((ip (car rule))
              (protocols (cdr rule)))
          (dolist (protocol protocols)
            (add-security-rule group (string-downcase (symbol-name protocol)) "1" "65535" ip))
          )))))
